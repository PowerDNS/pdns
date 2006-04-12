/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2003  PowerDNS.COM BV

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
// $Id$
#ifdef WIN32
# define WINDOWS_LEAN_AND_MEAN
# include <windows.h>
#else
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <sys/time.h>
# include <sys/wait.h>
# include <sys/mman.h>
#endif // WIN32

#include "utility.hh"
#include <cstdio>
#include <signal.h>
#include <cstring>
#include <cstdlib>
#include <sys/types.h>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>

#include "dns.hh"
#include "dnsbackend.hh"
#include "ueberbackend.hh"
#include "dnspacket.hh"
#include "nameserver.hh"
#include "distributor.hh"
#include "logger.hh"
#include "arguments.hh"
#include "packethandler.hh"
#include "statbag.hh"
#include "tcpreceiver.hh"
#include "packetcache.hh"
#include "ws.hh"
#include "misc.hh"
#include "dynlistener.hh"
#include "dynhandler.hh"
#include "communicator.hh"
#include "dnsproxy.hh"
#include "utility.hh"
#include "common_startup.hh"

time_t s_starttime;

string s_programname="pdns"; // used in packethandler.cc

char *funnytext=
"*****************************************************************************\n"\
"Ok, you just ran pdns_server through 'strings' hoping to find funny messages.\n"\
"Well, you found one. \n"\
"Two ions are flying through their particle accelerator, says the one to the\n"
"other 'I think I've lost an electron!' \n"\
"So the other one says, 'Are you sure?'. 'YEAH! I'M POSITIVE!'\n"\
"                                            the pdns crew - pdns@powerdns.com\n"
"*****************************************************************************\n";


// start (sys)logging

/** \var Logger L 
\brief All logging is done via L, a Logger instance
*/


/**
\file receiver.cc
\brief The main loop of powerdns 

This file is where it all happens - main is here, as are the two pivotal threads qthread() and athread()
*/


static void WIN32_declareArguments()
{
  arg().set("config-dir","Location of configuration directory (pdns.conf)")="./";  
  //arg().set("config-name","Name of this virtual configuration - will rename the binary image")="";
  arg().set("module-dir","Default directory for modules")="/../lib";

  arg().setSwitch( "register-service", "Register the service" )= "no";
  arg().setSwitch( "unregister-service", "Unregister the service" )= "no";
  arg().setSwitch( "ntservice", "Run as service" )= "no";

  arg().setSwitch( "use-ntlog", "Use the NT logging facilities" )= "yes";
  arg().setSwitch( "use-logfile", "Use a log file" )= "no"; 
  arg().setSwitch( "logfile", "Filename of the log file" )= "powerdns.log"; 
}

static void loadModules()
{
  L << Logger::Warning << Logger::NTLog << "The Windows version doesn't support dll loading (yet), none of the specified modules loaded" << std::endl;
}

//! Console handler.
BOOL WINAPI consoleHandler( DWORD ctrl )
{
  L << Logger::Error << "PowerDNS shutting down..." << endl;
  exit( 0 );

  // This will never be reached.
  return true;
}


//! The main function of pdns, the pdns process
int main(int argc, char **argv)
{ 
  s_programname="pdns";
  s_starttime=time(0);

  PDNSService pdns;

  // Initialize winsock.
  WSAData wsaData;

  if ( WSAStartup( MAKEWORD( 2, 0 ), &wsaData ) != 0 )
  {
    cerr << "Could not initialize winsock.dll" << endl;
    return -1;
  }

  L.toConsole(Logger::Warning);
  try {
    declareArguments();
    WIN32_declareArguments();
      
    arg().laxParse(argc,argv); // do a lax parse
    
    // If we have to run as a nt service change the current directory to the executable directory.
    if ( arg().mustDo( "ntservice" ))
    {
      char    dir[ MAX_PATH ];
      string  newdir;

      GetModuleFileName( NULL, dir, sizeof( dir ));

      newdir = dir;
      newdir = newdir.substr( 0, newdir.find_last_of( "\\" ));

      SetCurrentDirectory( newdir.c_str());
    }
    
    if(arg()["config-name"]!="") 
      s_programname+="-"+arg()["config-name"];
    
    (void)theL(s_programname);
    
    string configname=arg()["config-dir"]+"/"+s_programname+".conf";
    cleanSlashes(configname);

    if(!arg().mustDo("config") && !arg().mustDo("no-config")) // "config" == print a configuration file
      arg().laxFile(configname.c_str());
    
    arg().laxParse(argc,argv); // reparse so the commandline still wins
    L.toConsole((Logger::Urgency)(arg().asNum("loglevel")));  

    if(arg().mustDo("help") || arg().mustDo("config")) {
      arg().set("daemon")="no";
      arg().set("guardian")="no";
    }


    if ( arg().mustDo( "register-service" ))
    {
      if ( !pdns.registerService( "An advanced high performance authoritative nameserver.", true ))
      {
        cerr << "Could not register service." << endl;
        exit( 99 );
      }

      // Exit.
      exit( 0 );
    }

    if ( arg().mustDo( "unregister-service" ))
    {
      pdns.unregisterService();
      exit( 0 );
    }

    // we really need to do work - either standalone or as an instance
    BackendMakers().launch(arg()["launch"]); // vrooooom!
      
    if(arg().mustDo("version")) {
      cerr<<"Version: "VERSION", compiled on "<<__DATE__", "__TIME__<<endl;
      exit(99);
    }

    
    if(arg().mustDo("help")) {
      cerr<<"syntax:"<<endl<<endl;
      cerr<<arg().helpstring(arg()["help"])<<endl;
      exit(99);
    }
    
    if(arg().mustDo("config")) {
      cout<<arg().configstring()<<endl;
      exit(99);
    }

    if(arg().mustDo("list-modules")) {
      vector<string>modules=BackendMakers().getModules();
      cerr<<"Modules available:"<<endl;
      for(vector<string>::const_iterator i=modules.begin();i!=modules.end();++i)
	cout<<*i<<endl;

      exit(99);
    }
    if(!BackendMakers().numLauncheable()) {
      L<<Logger::Error<<"Unable to launch, no backends configured for querying"<<endl;
	exit(99); // this isn't going to fix itself either
    }

      if(arg().mustDo("control-console"))
	dl=new DynListener();
      else
	dl=new DynListener(s_programname);
      
    dl->registerFunc("SHOW",&DLShowHandler);
    dl->registerFunc("RPING",&DLPingHandler);
    dl->registerFunc("QUIT",&DLRQuitHandler);
    dl->registerFunc("UPTIME",&DLUptimeHandler);
    dl->registerFunc("NOTIFY-HOST",&DLNotifyHostHandler);
    dl->registerFunc("NOTIFY",&DLNotifyHandler);
    dl->registerFunc("RELOAD",&DLReloadHandler);
    dl->registerFunc("REDISCOVER",&DLRediscoverHandler);
    dl->registerFunc("VERSION",&DLVersionHandler);
    dl->registerFunc("PURGE",&DLPurgeHandler);
    dl->registerFunc("CCOUNTS",&DLCCHandler);
    dl->registerFunc("SET",&DLSettingsHandler);
    dl->registerFunc("RETRIEVE",&DLNotifyRetrieveHandler);

      
    // reparse, with error checking
    if(!arg().mustDo("no-config"))
      arg().file(configname.c_str());
    arg().parse(argc,argv);
    UeberBackend::go();
    N=new UDPNameserver; // this fails when we are not root, throws exception
    
    if(!arg().mustDo("disable-tcp"))
      TN=new TCPNameserver; 
  }
  catch(const ArgException &A) {
    L<<Logger::Error<<"Fatal error: "<<A.reason<<endl;
    exit(1);
  }
  
  declareStats();
  DLOG(L<<Logger::Warning<<"Verbose logging in effect"<<endl);
  
  if ( arg().mustDo( "use-ntlog" ) && arg().mustDo( "ntservice" ))
    L.toNTLog();

  if ( arg().mustDo( "use-logfile" ))
    L.toFile( arg()[ "logfile" ] );
  
  L<<Logger::Warning<<"PowerDNS "<<VERSION<<" (C) 2001-2003 PowerDNS.COM BV ("<<__DATE__", "__TIME__<<") starting up"<<endl;

  L<<Logger::Warning<<"PowerDNS comes with ABSOLUTELY NO WARRANTY. "
    "This is free software, and you are welcome to redistribute it "
    "according to the terms of the GPL version 2."<<endl;

  
  // Register console control hander.
  if ( !arg().mustDo( "ntservice" ))
    SetConsoleCtrlHandler( consoleHandler, true );
  
  PDNSService::instance()->start( argc, argv, arg().mustDo( "ntservice" ));
  
  WSACleanup();

  exit(1);
  
  return 0;
}



