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
// $Id: win32_dynlistener.cc,v 1.2 2003/11/30 10:53:17 ahu Exp $ 
/* (C) Copyright 2002 PowerDNS.COM BV */
#include "utility.hh"
#include <string>
#include <map>
#include <sys/types.h>
#include <pthread.h>

#include <errno.h>
#include <iostream>
#include <sstream>
#include <sys/types.h>
#include <signal.h>

#include <sys/stat.h>
#include <fcntl.h>

#include "misc.hh"
#include "dns.hh"
#include "arguments.hh"
#include "dnsbackend.hh"
#include "dynlistener.hh"
#include "dnspacket.hh"
#include "logger.hh"
#include "statbag.hh"
#include "pdnsservice.hh"



extern StatBag S;

DynListener::DynListener(const string &pname)
{
  d_restfunc=0;
  string programname=pname;

  if(!programname.empty()) {
    string pipename = "\\\\.\\pipe\\" + programname;

    m_pipeHandle = CreateNamedPipe( 
      pipename.c_str(),
      PIPE_ACCESS_DUPLEX,
      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
      PIPE_UNLIMITED_INSTANCES,
      1024,
      1024,
      5000,
      NULL );
    
    if ( m_pipeHandle == INVALID_HANDLE_VALUE )
    {
      L << Logger::Error << "creating named pipe for dynlistener failed." << endl;
      exit( 1 );
    }

    L<<Logger::Warning<<"Listening on named pipe." << endl;
    d_udp=true;
  }
  else
    d_udp=false;
  

}

void DynListener::go()
{
  d_ppid=Utility::getpid();
  pthread_create(&d_tid,0,&DynListener::theListenerHelper,this);
}

void *DynListener::theListenerHelper(void *p)
{
  DynListener *us=static_cast<DynListener *>(p);
  us->theListener();
  return 0;
}

string DynListener::getLine()
{
  char mesg[512];
  memset(mesg,0,512);
  
  DWORD bytesRead;

  if ( !ConnectNamedPipe( m_pipeHandle, NULL ))
    throw AhuException( "Reading from named pipe failed." );

  if ( !ReadFile( m_pipeHandle, mesg, sizeof( mesg ), &bytesRead, NULL ))
    throw AhuException( "Reading from named pipe failed." );  

  return mesg;
}

void DynListener::sendLine(const string &l)
{
  unsigned long bytesWritten;

  string line = l;
  line.append( "\r\n" );

  if ( !WriteFile( m_pipeHandle, line.c_str(), line.length(), &bytesWritten, NULL ))
    return; // Could not write.

  FlushFileBuffers( m_pipeHandle );
  DisconnectNamedPipe( m_pipeHandle );
}

void DynListener::registerFunc(const string &name, g_funk_t *gf)
{
  d_funcdb[name]=gf;
}

void DynListener::registerRestFunc(g_funk_t *gf)
{
  d_restfunc=gf;
}

void DynListener::theListener()
{
  try {
    map<string,string> parameters;

    for(;;) {
      string line=getLine();
      chomp(line,"\n");

      vector<string>parts;
      stringtok(parts,line," ");
      if(parts.empty()) {
	sendLine("Empty line");
	continue;
      }
      parts[0] = toUpper( parts[0] ); 
      if(!d_funcdb[parts[0]]) {
	if(d_restfunc) 
	  sendLine((*d_restfunc)(parts,d_ppid));
	else
	  sendLine("Unknown command: '"+parts[0]+"'");
	continue;
      }

      sendLine((*d_funcdb[parts[0]])(parts,d_ppid));
    }
  }
  catch(AhuException &AE)
    {
      L<<Logger::Error<<"Fatal: "<<AE.reason<<endl;
    }
  catch(string &E)
    {
      L<<Logger::Error<<"Fatal: "<<E<<endl;
    }
    catch( ... )
    {
      L<<Logger::Error<<"Fatal: unknown exception occured"<<endl;
    }
}

 
