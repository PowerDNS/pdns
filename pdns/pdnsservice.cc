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

#include "common_startup.hh"
#include "pdnsservice.hh"


// Control handler.
void PDNSService::ctrlHandler( DWORD controlCode )
{
  if ( m_statusCode == SERVICE_STOPPED )
    exit( 0 );

  switch ( controlCode )
  {
    case SERVICE_CONTROL_STOP:
      setStatus( SERVICE_STOP_PENDING );
      shutdown();
      setStatus( SERVICE_STOPPED );
      // FIXME: Add a cleaner way to do this:
      break;

    case SERVICE_CONTROL_INTERROGATE:
      setStatus( m_statusCode, m_errorCode );
      break;

    case SERVICE_CONTROL_SHUTDOWN:
      setStatus( SERVICE_STOP_PENDING );
      shutdown();
      setStatus( SERVICE_STOPPED );
      // FIXME: Add a cleaner way to do this:
      break;
  }
}


// Returns the service name.
std::string PDNSService::getServiceName( void )
{
  return "PowerDNS";
}


// Main procedure.
int PDNSService::main( int argc, char *argv[] )
{
  try
  {
    L << Logger::Info << Logger::NTLog << "PowerDNS " << VERSION << " (C) 2001-2003 PowerDNS.COM BV (" << __DATE__ ", " __TIME__<< ") starting up" << endl;
    mainthread();
  }
  catch(AhuException &AE) {
    if(!PDNSService::isRunningAsService())
      cerr<<"Exiting because: "<<AE.reason<<endl;
    L<<Logger::Error<<Logger::NTLog<<"Exiting because: "<<AE.reason<<endl;
  }      
  catch(...) {
    cerr<<"Uncaught exception of unknown type - sorry"<<endl;
  }

  return 0;
}
