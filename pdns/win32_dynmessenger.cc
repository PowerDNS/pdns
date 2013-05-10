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
#include "dynmessenger.hh"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <iostream>
#include <sys/types.h>


DynMessenger::DynMessenger(const string &dname, const string &fname)
{
  string pipename = "\\\\.\\pipe\\" + fname;

  m_pipeHandle = CreateFile( pipename.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL );
  if ( m_pipeHandle == INVALID_HANDLE_VALUE )
    throw AhuException( "Could not create named pipe (are you on Windows NT, 2000 or XP? 98 doesn't work!)" );
}

DynMessenger::~DynMessenger()
{
  CloseHandle( m_pipeHandle );
}

int DynMessenger::send(const string &msg) const
{
  unsigned long bytesWritten;

  if ( !WriteFile( m_pipeHandle, msg.c_str(), msg.length(), &bytesWritten, NULL ))
    return -1; // Could not write.

  FlushFileBuffers( m_pipeHandle );

  return 0;
}

string DynMessenger::receive() const
{
  char buffer[1024];

  DWORD bytesRead;

  if ( !ReadFile( m_pipeHandle, buffer, sizeof( buffer ) - 1, &bytesRead, NULL ))
    return "";

  buffer[ bytesRead ] = 0;

  return buffer;
}


