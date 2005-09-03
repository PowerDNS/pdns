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

/*!
\file ntservice.cpp
\brief This file contains the NTService class implementation.
*/

#include "utility.hh"
#include <sstream>
#include <iostream>
#include "logger.hh"
#include "ntservice.hh"

#define L theL("pdns")


// Default constructor.
NTService::NTService( void )
{
  m_runningAsService    = false;
  m_errorCode           = 0;
  m_statusCode          = 0;
  m_serviceStatusHandle = NULL;
}


// Destructor.
NTService::~NTService( void )
{
}


// Returns whether the program is running as a service.
bool NTService::isRunningAsService( void )
{
  return m_runningAsService;
}


// Registers the service.
bool NTService::registerService( const std::string & description, bool registerLog )
{
  std::stringstream str;
  HKEY              key, pkey;
  SC_HANDLE         sc;
  char              temp[ 512 ];
  DWORD             flags;
  
  sc = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
  if ( sc == NULL )
    return false; // Could not open the Service Control Manager.

  GetModuleFileName( NULL, temp, sizeof( temp ));

  str << temp << " --ntservice";
  if ( CreateService( 
    sc, 
    getServiceName().c_str(), 
    getServiceName().c_str(),
    SERVICE_ALL_ACCESS,
    SERVICE_WIN32_OWN_PROCESS,
    SERVICE_AUTO_START,
    SERVICE_ERROR_NORMAL,
    str.str().c_str(),
    NULL,
    NULL,
    NULL,
    NULL,
    NULL ) == NULL && GetLastError() != ERROR_SERVICE_EXISTS )
  {
    return false; // Don't we all like functions with 43 billion parameters?
  }

  CloseServiceHandle( sc );

  str.str( "" );
  
  // Set description.
  if ( !description.empty())
  {
    str << "SYSTEM\\CurrentControlSet\\Services\\" << getServiceName();

    if ( RegCreateKey( HKEY_LOCAL_MACHINE, str.str().c_str(), &key ) != ERROR_SUCCESS )
      return false;

    if ( RegSetValueEx( key, "Description", 0, REG_SZ, reinterpret_cast< const unsigned char * >( description.c_str()), description.length()) != ERROR_SUCCESS )
    {
      RegCloseKey( key );
      return false;
    }

    RegCloseKey( key );
  }

  // Register event log.
  if ( registerLog )
  {
    str.str( "" );

    str << "SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Application\\" << getServiceName();
    if ( RegCreateKey( HKEY_LOCAL_MACHINE, str.str().c_str(), &pkey ) != ERROR_SUCCESS )
      return false;

    flags = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
    
    if ( RegSetValueEx( pkey, "TypesSupported", 0, REG_DWORD, reinterpret_cast< const unsigned char * >( &flags ), sizeof( flags )) != ERROR_SUCCESS )
    {
      RegCloseKey( pkey );
      return false;
    }

    // For the message file this function assumes %SystemRoot%\\System32\\<servicename>msg.dll
    str.str( "" );

    char path[ MAX_PATH ];
    GetCurrentDirectory( sizeof( path ), path );

    // FIXME: This really should be: str << path << "\\" << getServiceName() << "msg.dll";
    str << path << "\\pdnsmsg.dll";
    if ( RegSetValueEx( pkey, "EventMessageFile", 0, REG_SZ, reinterpret_cast< const unsigned char * >( str.str().c_str()), str.str().length()) != ERROR_SUCCESS )
    {
      RegCloseKey( pkey );
      return false;
    }

    RegCloseKey( pkey );
  }
  
  return true;
}


// Calls the control handler.
void WINAPI NTService::s_ctrlHandler( DWORD controlCode )
{
  NTService::instance()->ctrlHandler( controlCode );
}


// Calls the service's main function.
void WINAPI NTService::s_serviceMain( DWORD argc, LPTSTR *argv )
{
  // IEEEEUUWWWW!!
  
  NTService::instance()->m_serviceStatusHandle = RegisterServiceCtrlHandler( NTService::instance()->getServiceName().c_str(), s_ctrlHandler );
  if ( NTService::instance()->m_serviceStatusHandle == 0 )
  {
    // Could not register service ctrl handler.
    return;
  }

  NTService::instance()->setStatus( SERVICE_START_PENDING );
  // Initialize.
  if ( !NTService::instance()->init())
  {
    NTService::instance()->setStatus( SERVICE_STOPPED, -1 );
    return;
  }

  NTService::instance()->setStatus( SERVICE_RUNNING );
  
  // Run.
  NTService::instance()->main( argc, argv );

  NTService::instance()->setStatus( SERVICE_STOP_PENDING );

  // Shut down.
  NTService::instance()->shutdown();
  
  NTService::instance()->setStatus( SERVICE_STOPPED );
}


// Sets the service's status.
void NTService::setStatus( DWORD status, DWORD error )
{
  SERVICE_STATUS stat;

  if ( !m_serviceStatusHandle )
    return;

  stat.dwServiceType              = SERVICE_WIN32_OWN_PROCESS;
  stat.dwCurrentState             = status;
  stat.dwControlsAccepted         = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
  stat.dwWin32ExitCode            = ( error ? ERROR_SERVICE_SPECIFIC_ERROR : NO_ERROR );
  stat.dwServiceSpecificExitCode  = error;
  stat.dwCheckPoint               = 0;
  stat.dwWaitHint                 = 0;

  SetServiceStatus( m_serviceStatusHandle, &stat );  
}


// Starts the service.
int NTService::start( int argc, char *argv[], bool asService )
{
  int res = 0;
  char name[ 128 ];

  strncpy( name, getServiceName().c_str(), sizeof( name ));
  
  SERVICE_TABLE_ENTRY entries[] =
  {
    { name, s_serviceMain },
    { NULL, NULL }
  };
  
  if ( asService )
  {
    // Run as service.
    m_runningAsService = true;

    if ( StartServiceCtrlDispatcher( entries ))
      return 0; // Success!

    // StartServiceCtrlDispatcher() failed, check if we should run as a normal
    // console program.
    if ( GetLastError() != ERROR_FAILED_SERVICE_CONTROLLER_CONNECT )
      return -1;

  }

  DLOG( L << "Running as a normal (console) program." << endl );

  // Run as normal (console) program.
  m_runningAsService = false;

  if ( !init())
    return -1; // Could not initialize.

  // Run.
  res = main( argc, argv );

  shutdown();

  return res;
}


// Stops the service.
bool NTService::stop( void )
{
  if ( !isRunningAsService())
    exit( 0 );

  setStatus( SERVICE_STOPPED, 0 );

  return true;
}


// Unregister service.
bool NTService::unregisterService( void )
{
  HKEY      key;
  SC_HANDLE sc, svc;

  sc = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
  if ( sc == NULL )
    return false;
  
  svc = OpenService( sc, getServiceName().c_str(), DELETE );
  if ( GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST )
  {
    if ( svc == NULL )
    {
      CloseServiceHandle( sc );
      return false;
    }

    DeleteService( svc );
    CloseServiceHandle( svc );
    CloseServiceHandle( sc );
  }

  if ( RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application", 0, KEY_WRITE, &key ) != ERROR_SUCCESS )
    return false;

  RegDeleteKey( key, getServiceName().c_str());

  RegCloseKey( key );
  
  return true;
}
