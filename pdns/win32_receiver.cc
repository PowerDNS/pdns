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

// $Id: win32_receiver.cc,v 1.1 2002/11/29 22:09:59 ahu Exp $
#include "utility.hh"
#include <cstdio>
#include <signal.h>
#include <cstring>
#include <cstdlib>
#include <sys/types.h>
#include <iostream>
#include <string>
#include <errno.h>
#include <pthread.h>
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
#include "pdnsservice.hh"
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


void daemonize(void)
{
}


static int cpid;

static void takedown(int i)
{
  if(cpid) {
    L<<Logger::Error<<"Guardian is killed, taking down children with us"<<endl;
#ifndef WIN32
    Utility::Signal::kill(cpid,SIGKILL);
#endif // WIN32
    exit(1);
  }
}


static void writePid(void)
{
}

int d_fd1[2], d_fd2[2];
FILE *d_fp;

static string DLRestHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  // TODO: Implement this.
#ifndef WIN32
  string line;
  
  for(vector<string>::const_iterator i=parts.begin();i!=parts.end();++i) {
    if(i!=parts.begin())
      line.append(1,' ');
    line.append(*i);
  }
  line.append(1,'\n');
  
  write(d_fd1[1],line.c_str(),line.size()+1);
  char mesg[512];
  fgets(mesg,511,d_fp);
  line=mesg;
  chomp(line,"\n");
  return line;

#else
  return "";

#endif // WIN32
}

static string DLCycleHandler(const vector<string>&parts, pid_t ppid)
{
#ifndef WIN32
  Utility::Signal::kill(cpid,SIGKILL);
#endif // WIN32
  return "ok";
}

static int guardian(int argc, char **argv)
{
  // TODO: Implement this?
#ifdef WIN32
  return 0;

#else

  if(isGuarded(argv))
    return 0;

  int infd=0, outfd=1;

  DynListener dlg(s_programname);
  dlg.registerFunc("QUIT",&DLQuitHandler);
  dlg.registerFunc("CYCLE",&DLCycleHandler);
  dlg.registerFunc("PING",&DLPingHandler);
  dlg.registerFunc("STATUS",&DLStatusHandler);
  dlg.registerRestFunc(&DLRestHandler);
  dlg.go();
  string progname=argv[0];

  bool first=true;
  cpid=0;

  for(;;) {
    int pid;
    setStatus("Launching child");

    if(pipe(d_fd1)<0 || pipe(d_fd2)<0) {
      L<<Logger::Critical<<"Unable to open pipe for coprocess: "<<strerror(errno)<<endl;
      exit(1);
    }

    if(!(pid=fork())) { // child
      signal(SIGTERM, SIG_DFL);

      signal(SIGHUP, SIG_DFL);
      signal(SIGUSR1, SIG_DFL);
      signal(SIGUSR2, SIG_DFL);

      char **const newargv=new char*[argc+2];
      int n;

      if(arg()["config-name"]!="") {
	progname+="-"+arg()["config-name"];
	L<<Logger::Error<<"Virtual configuration name: "<<arg()["config-name"]<<endl;
      }

      newargv[0]=strdup(const_cast<char *>((progname+"-instance").c_str()));
      for(n=1;n<argc;n++) {
	newargv[n]=argv[n];
      }
      newargv[n]=0;
      
      L<<Logger::Error<<"Guardian is launching an instance"<<endl;
      close(d_fd1[1]);
      close(d_fd2[0]);

      if(d_fd1[0]!= infd) {
	dup2(d_fd1[0], infd);
	close(d_fd1[0]);
      }

      if(d_fd2[1]!= outfd) {
	dup2(d_fd2[1], outfd);
	close(d_fd2[1]);
      }
      if(execv(argv[0], newargv)<0) {
	L<<Logger::Error<<"Unable to execv '"<<argv[0]<<"': "<<strerror(errno)<<endl;
	char **p=newargv;
	while(*p)
	  L<<Logger::Error<<*p++<<endl;

	exit(1);
      }
      L<<Logger::Error<<"execve returned!!"<<endl;
      // never reached
    }
    else if(pid>0) { // parent
      close(d_fd1[0]);
      close(d_fd2[1]);
      if(!(d_fp=fdopen(d_fd2[0],"r"))) {
	L<<Logger::Critical<<"Unable to associate a file pointer with pipe: "<<stringerror()<<endl;
	exit(1);
      }
      setbuf(d_fp,0); // no buffering please, confuses select

      if(first) {
	first=false;
	signal(SIGTERM, takedown);

	signal(SIGHUP, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);
	signal(SIGUSR2, SIG_IGN);

	writePid();
      }

      int status;
      cpid=pid;
      for(;;) {
	int ret=waitpid(pid,&status,WNOHANG);

	if(ret<0) {
	  L<<Logger::Error<<"In guardian loop, waitpid returned error: "<<strerror(errno)<<endl;
	  L<<Logger::Error<<"Dying"<<endl;
	  exit(1);
	}
	else if(ret) // something exited
	  break;
	else { // child is alive
	  // execute some kind of ping here 
	  if(DLQuitPlease())
	    takedown(1);
	  setStatus("Child running on pid "+itoa(pid));
	  sleep(1);
	}
      }
      close(d_fd1[1]);
      fclose(d_fp);

      if(WIFEXITED(status)) {
	int ret=WEXITSTATUS(status);

	if(ret==99) {
	  L<<Logger::Error<<"Child requested a stop, exiting"<<endl;
	  exit(1);
	}
	setStatus("Child died with code "+itoa(ret));
	L<<Logger::Error<<"Our pdns instance exited with code "<<ret<<endl;
	L<<Logger::Error<<"Respawning"<<endl;

	sleep(1);
	continue;
      }
      if(WIFSIGNALED(status)) {
	int sig=WTERMSIG(status);
	setStatus("Child died because of signal "+itoa(sig));
	L<<Logger::Error<<"Our pdns instance ("<<pid<<") exited after signal "<<sig<<endl;
#ifdef WCOREDUMP
	if(WCOREDUMP(status)) 
	  L<<Logger::Error<<"Dumped core"<<endl;
#endif

	L<<Logger::Error<<"Respawning"<<endl;
	sleep(1);
	continue;
      }
      L<<Logger::Error<<"No clue what happened! Respawning"<<endl;
    }
    else {
      L<<Logger::Error<<"Unable to fork: "<<strerror(errno)<<endl;
      exit(1);
    }
  }

#endif // WIN32
}

static void WIN32_declareArguments()
{

  arg().set("config-dir","Location of configuration directory (pdns.conf)")="./";  
  //arg().set("config-name","Name of this virtual configuration - will rename the binary image")="";
  arg().set("module-dir","Default directory for modules")="/../lib";

  arg().setSwitch( "register-service", "Register the service" )= "no";
  arg().setSwitch( "unregister-service", "Unregister the service" )= "no";
  arg().setSwitch( "ntservice", "Run as service" )= "no";

  arg().setSwitch( "use-ntlog", "Use the NT logging facilities" )= "yes";

}

static void loadModules()
{
  if(!arg()["load-modules"].empty()) { 
    vector<string>modules;
    
    stringtok(modules,arg()["load-modules"],",");
    
    for(vector<string>::const_iterator i=modules.begin();i!=modules.end();++i) {
      bool res;
      const string &module=*i;
      
      if(module.find(".")==string::npos)
	res=UeberBackend::loadmodule(arg()["module-dir"]+"/lib"+module+"backend.so");
      else if(module[0]=='/' || (module[0]=='.' && module[1]=='/') || (module[0]=='.' && module[1]=='.'))    // absolute or current path
	res=UeberBackend::loadmodule(module);
      else
	res=UeberBackend::loadmodule(arg()["module-dir"]+"/"+module);
      
      if(res==false) {
	L<<Logger::Error<<"Unable to load module "<<module<<endl;
	exit(1);
      }
    }
  }
}


//! Console handler.
BOOL WINAPI consoleHandler( DWORD ctrl )
{
  L << Logger::Error << "PDNS shutting down..." << endl;
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
    
    if(arg()["config-name"]!="") 
      s_programname+="-"+arg()["config-name"];

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
    
    (void)theL(s_programname);
    
    string configname=arg()["config-dir"]+"/"+s_programname+".conf";
    cleanSlashes(configname);

    if(!arg().mustDo("config") && !arg().mustDo("no-config"))
      arg().laxFile(configname.c_str());
    
    arg().laxParse(argc,argv); // reparse so the commandline still wins
    L.toConsole((Logger::Urgency)(arg().asNum("loglevel")));  

    if(arg().mustDo("help") || arg().mustDo("config")) {
      arg().set("daemon")="no";
      arg().set("guardian")="no";
    }

    if(arg().mustDo("guardian") && !isGuarded(argv)) {
      //guardian(argc, argv);  
      // never get here, guardian will reinvoke process
      //cerr<<"Um, we did get here!"<<endl;
      cerr << "Guardian mode isn't supported on Windows (yet)." << endl;
      exit( 0 );
    }
    

    if ( arg().mustDo( "register-service" ))
    {
      if ( !pdns.registerService( "An advanced high performance authoritative nameserver.", true ))
        cerr << "Could not register service." << endl;

      // Exit.
      exit( 0 );
    }

    if ( arg().mustDo( "unregister-service" ))
    {
      pdns.unregisterService();
      exit( 0 );
    }

    // we really need to do work - either standalone or as an instance
    
    loadModules();
    BackendMakers().launch(arg()["launch"]); // vrooooom!
      
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
      L<<Logger::Error<<Logger::NTLog<<"Unable to launch, no backends configured for querying"<<endl;
	exit(99); // this isn't going to fix itself either
    }

    
    if(isGuarded(argv)) {
      L<<Logger::Warning<<"This is a guarded instance of pdns"<<endl;
      dl=new DynListener; // listens on stdin 
    }
    else {
      L<<Logger::Warning<<"This is a standalone pdns"<<endl; 
      
      if(arg().mustDo("control-console"))
	dl=new DynListener();
      else
	dl=new DynListener(s_programname);
      
      writePid();
    }
    dl->registerFunc("SHOW",&DLShowHandler);
    dl->registerFunc("RPING",&DLPingHandler);
    dl->registerFunc("QUIT",&DLRQuitHandler);
    dl->registerFunc("UPTIME",&DLUptimeHandler);
    dl->registerFunc("NOTIFY-HOST",&DLNotifyHostHandler);
    dl->registerFunc("NOTIFY",&DLNotifyHandler);
    dl->registerFunc("RELOAD",&DLReloadHandler);
    dl->registerFunc("REDISCOVER",&DLRediscoverHandler);
    dl->registerFunc("VERSION",&DLVersionHandler);

      
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
  
  L<<Logger::Error<<Logger::NTLog<<"PowerDNS "<<VERSION<<" ("<<__DATE__<<", "<<__TIME__<<") starting up"<<endl;
  L<<Logger::Error<<"NOT-FOR-PROFIT LICENSE"<<endl;
  
  // Register console control hander.
  if ( !arg().mustDo( "ntservice" ))
    SetConsoleCtrlHandler( consoleHandler, true );
  
  PDNSService::instance()->start( argc, argv, arg().mustDo( "ntservice" ));
  
  exit(1);
  
  return 1;
}



