/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "utility.hh"
#include "pdnsservice.hh"
#include "logger.hh"
#include "statbag.hh"
#include "pdnsmsg.hh"

using namespace std;

Logger &theL(const string &pname)
{
  static Logger l("");
  if(!pname.empty())
    l.setName(pname);
  return l;
}

void Logger::log(const string &msg, Urgency u)
{
  const char *heheDirtyAndNastyHack[ 2 ];

  heheDirtyAndNastyHack[ 0 ] = msg.c_str();
  heheDirtyAndNastyHack[ 1 ] = NULL;

  extern StatBag S;
  S.ringAccount("logmessages",msg);

  if ( m_pLogFile != NULL )
  {
    char timestr[ 128 ];
    time_t curtime;
    ostringstream message;

    curtime = time( NULL );
    strftime( timestr, sizeof( timestr ), "%a %d %b %X", localtime( &curtime ));
    
    message << timestr << " (" << u << "): " << msg << endl;
    fwrite( message.str().c_str(), sizeof( char ), message.str().length(), m_pLogFile );
    fflush( m_pLogFile );
  }

  if ( PDNSService::instance())
  {
    if ( !PDNSService::instance()->isRunningAsService() && u <= consoleUrgency )
    {
      clog << msg << endl;
      return;
    }
  }

  if ( !opened )
    return;

  if ( m_eventLogHandle == NULL )
    return;
  
  // Only log relevant messages.
  //if ( m_toNTLog.find( pthread_self()) == m_toNTLog.end())
  //  return;

  if ( m_toNTLog[ pthread_self() ] == false )
    return;
  
  //if ( u == EVENTLOG_INFORMATION_TYPE )
  //  return; // Don't spam the NT log.

  DWORD eventId;
  switch ( u )
  {
  case EVENTLOG_ERROR_TYPE:
    eventId = MSG_ERROR;
    break;

  case EVENTLOG_WARNING_TYPE:
    eventId = MSG_WARNING;
    break;

  default:
    eventId = MSG_INFO;
  }
  
  ReportEvent( m_eventLogHandle, u, 0, eventId, NULL, 1, 0, heheDirtyAndNastyHack, NULL );
}

void Logger::toConsole(Urgency u)
{

  consoleUrgency=u;
}


void Logger::toFile( const string & filename )
{
  m_pLogFile = fopen( filename.c_str(), "at" );
}


void Logger::toNTLog( void )
{
  m_eventLogHandle = RegisterEventSource( NULL, NTService::instance()->getServiceName().c_str());
}

void Logger::open()
{
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
  flags=0;
  d_facility=facility;
  consoleUrgency=Error;
  name=n;
  m_pLogFile = NULL;
  m_eventLogHandle = NULL;
  pthread_mutex_init(&lock,0);
  open();
}

Logger& Logger::operator<<(Urgency u)
{
  pthread_mutex_lock(&lock);

  if ( u == NTLog )
    m_toNTLog[ pthread_self() ] = true;
  else
    d_outputurgencies[pthread_self()]=u;

  pthread_mutex_unlock(&lock);
  return *this;
}

Logger& Logger::operator<<(const string &s)
{
  pthread_mutex_lock(&lock);

  if(!d_outputurgencies.count(pthread_self())) // default urgency
    d_outputurgencies[pthread_self()]=Info;

  if ( !m_toNTLog.count( pthread_self()))
    m_toNTLog[ pthread_self() ] = false;

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

Logger& Logger::operator<<( ostream & (blah)(ostream &))
{
  // *this<<" ("<<(int)d_outputurgencies[pthread_self()]<<", "<<(int)consoleUrgency<<")";
  pthread_mutex_lock(&lock);


  log(d_strings[pthread_self()], d_outputurgencies[pthread_self()]);
  d_strings.erase(pthread_self());  
  d_outputurgencies.erase(pthread_self());
  m_toNTLog.erase( pthread_self());

  pthread_mutex_unlock(&lock);
  return *this;
}

