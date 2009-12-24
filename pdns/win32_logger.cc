/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation
    

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "utility.hh"
#include "logger.hh"
#include "ntservice.hh" 
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
  const char *tmp[ 2 ];

  tmp[ 0 ] = msg.c_str();
  tmp[ 1 ] = NULL;

  char timestr[ 128 ];
  time_t curtime= time( NULL );
  strftime( timestr, sizeof( timestr ), "%a %d %b %X", localtime( &curtime ));

  if ( m_pLogFile != NULL )
  {
    ostringstream message;
    message << timestr << " (" << u << "): " << msg << endl;
    fwrite( message.str().c_str(), sizeof( char ), message.str().length(), m_pLogFile );
    fflush( m_pLogFile );
  }
  if(m_eventLogHandle)
    ReportEvent( m_eventLogHandle, u, 0, MSG_WARNING, NULL, 1, 0, tmp, NULL );

  clog << timestr<<" " <<msg << endl;
  return;
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
  m_eventLogHandle = RegisterEventSource( NULL, 
          NTService::instance()->getServiceName().c_str());
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
  open();
}

Logger& Logger::operator<<(Urgency u)
{
  d_outputurgencies[0]=u;
  return *this;
}

Logger& Logger::operator<<(const string &s)
{
  if(!d_outputurgencies.count(0)) // default urgency
    d_outputurgencies[0]=Info;

  if ( !m_toNTLog.count( 0))
    m_toNTLog[ 0 ] = false;

  //  if(d_outputurgencies[0]<=(unsigned int)consoleUrgency) // prevent building strings we won't ever print
      d_strings[0].append(s);

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


Logger& Logger::operator<<( ostream & (blah)(ostream &))
{
  log(d_strings[0], d_outputurgencies[0]);

  d_strings.erase(0);  
  d_outputurgencies.erase(0);

  return *this;
}

