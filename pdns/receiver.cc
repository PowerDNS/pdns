/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2008  PowerDNS.COM BV

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
#include "packetcache.hh"

#include <cstdio>
#include <signal.h>
#include <cstring>
#include <cstdlib>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <fstream>
#include <boost/algorithm/string.hpp>

#include "config.h"
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
#include "ws.hh"
#include "misc.hh"
#include "dynlistener.hh"
#include "dynhandler.hh"
#include "communicator.hh"
#include "dnsproxy.hh"
#include "utility.hh"
#include "common_startup.hh"
#include "dnsrecords.hh"


time_t s_starttime;

string s_programname="pdns"; // used in packethandler.cc

const char *funnytext=
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
  if(fork())
    exit(0); // bye bye
  
  setsid(); 

  int i=open("/dev/null",O_RDWR); /* open stdin */
  if(i < 0) 
    L<<Logger::Critical<<"Unable to open /dev/null: "<<stringerror()<<endl;
  else {
    dup2(i,0); /* stdin */
    dup2(i,1); /* stderr */
    dup2(i,2); /* stderr */
    close(i);
  }
}


static int cpid;

static void takedown(int i)
{
  if(cpid) {
    L<<Logger::Error<<"Guardian is killed, taking down children with us"<<endl;
    kill(cpid,SIGKILL);
    exit(1);
  }
}

static void writePid(void)
{
  string fname=::arg()["socket-dir"]+"/"+s_programname+".pid";
  ofstream of(fname.c_str());
  if(of)
    of<<getpid()<<endl;
  else
    L<<Logger::Error<<"Requested to write pid for "<<getpid()<<" to "<<fname<<" failed: "<<strerror(errno)<<endl;
}

int d_fd1[2], d_fd2[2];
FILE *d_fp;

static string DLRestHandler(const vector<string>&parts, pid_t ppid)
{
  string line;
  
  for(vector<string>::const_iterator i=parts.begin();i!=parts.end();++i) {
    if(i!=parts.begin())
      line.append(1,' ');
    line.append(*i);
  }
  line.append(1,'\n');
  
  write(d_fd1[1],line.c_str(),line.size()+1);
  char mesg[512];
  string response;
  while(fgets(mesg,sizeof(mesg),d_fp)) {
    if(*mesg=='\n')
      break;
    response+=mesg;
  }
  boost::trim_right(response);
  return response;
}

static string DLCycleHandler(const vector<string>&parts, pid_t ppid)
{
  kill(cpid,SIGKILL); // why?
  kill(cpid,SIGKILL); // why?
  
  sleep(1);
  return "ok";
}

static int guardian(int argc, char **argv)
{
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

      if(::arg()["config-name"]!="") {
	progname+="-"+::arg()["config-name"];
	L<<Logger::Error<<"Virtual configuration name: "<<::arg()["config-name"]<<endl;
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
      if(execvp(argv[0], newargv)<0) {
	L<<Logger::Error<<"Unable to execvp '"<<argv[0]<<"': "<<strerror(errno)<<endl;
	char **p=newargv;
	while(*p)
	  L<<Logger::Error<<*p++<<endl;

	exit(1);
      }
      L<<Logger::Error<<"execvp returned!!"<<endl;
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
}

static void UNIX_declareArguments()
{
  static char pietje[128]="!@@SYSCONFDIR@@:";
  ::arg().set("config-dir","Location of configuration directory (pdns.conf)")=
    strcmp(pietje+1,"@@SYSCONFDIR@@:") ? pietje+strlen("@@SYSCONFDIR@@:")+1 : SYSCONFDIR;
  
  ::arg().set("config-name","Name of this virtual configuration - will rename the binary image")="";
  ::arg().set("socket-dir","Where the controlsocket will live")=LOCALSTATEDIR;
  ::arg().set("module-dir","Default directory for modules")=LIBDIR;
  ::arg().set("chroot","If set, chroot to this directory for more security")="";
  ::arg().set("logging-facility","Log under a specific facility")="";
  ::arg().set("daemon","Operate as a daemon")="no";

}

static void loadModules()
{
  if(!::arg()["load-modules"].empty()) { 
    vector<string>modules;
    
    stringtok(modules,::arg()["load-modules"],",");
    
    for(vector<string>::const_iterator i=modules.begin();i!=modules.end();++i) {
      bool res;
      const string &module=*i;
      
      if(module.find(".")==string::npos)
	res=UeberBackend::loadmodule(::arg()["module-dir"]+"/lib"+module+"backend.so");
      else if(module[0]=='/' || (module[0]=='.' && module[1]=='/') || (module[0]=='.' && module[1]=='.'))    // absolute or current path
	res=UeberBackend::loadmodule(module);
      else
	res=UeberBackend::loadmodule(::arg()["module-dir"]+"/"+module);
      
      if(res==false) {
	L<<Logger::Error<<"receiver unable to load module "<<module<<endl;
	exit(1);
      }
    }
  }
}



#ifdef __linux__
#include <execinfo.h>
static void tbhandler(int num)
{
  L<<Logger::Critical<<"Got a signal "<<num<<", attempting to print trace: "<<endl;
  void *array[20]; //only care about last 17 functions (3 taken with tracing support)
  size_t size;
  char **strings;
  size_t i;
  
  size = backtrace (array, 20);
  strings = backtrace_symbols (array, size); //Need -rdynamic gcc (linker) flag for this to work
  
  for (i = 0; i < size; i++) //skip useless functions
    L<<Logger::Error<<strings[i]<<endl;
  
  
  signal(SIGABRT, SIG_DFL);
  abort();//hopefully will give core

}
#endif

//! The main function of pdns, the pdns process
int main(int argc, char **argv)
{ 
  reportAllTypes(); // init MOADNSParser

  s_programname="pdns";
  s_starttime=time(0);

#ifdef __linux__
  signal(SIGSEGV,tbhandler);
  signal(SIGFPE,tbhandler);
  signal(SIGABRT,tbhandler);
  signal(SIGILL,tbhandler);
#endif


  L.toConsole(Logger::Warning);
  try {
    declareArguments();
    UNIX_declareArguments();
      
    ::arg().laxParse(argc,argv); // do a lax parse
    
    if(::arg()["config-name"]!="") 
      s_programname+="-"+::arg()["config-name"];
    
    (void)theL(s_programname);
    
    string configname=::arg()["config-dir"]+"/"+s_programname+".conf";
    cleanSlashes(configname);

    if(!::arg().mustDo("config") && !::arg().mustDo("no-config")) // "config" == print a configuration file
      ::arg().laxFile(configname.c_str());
    
    ::arg().laxParse(argc,argv); // reparse so the commandline still wins
    if(!::arg()["logging-facility"].empty()) {
      boost::optional<int> val=logFacilityToLOG(::arg().asNum("logging-facility") );
      if(val)
	theL().setFacility(*val);
      else
	L<<Logger::Error<<"Unknown logging facility "<<::arg().asNum("logging-facility") <<endl;
    }

    L.setLoglevel((Logger::Urgency)(::arg().asNum("loglevel")));
    L.toConsole((Logger::Urgency)(::arg().asNum("loglevel")));  

    if(::arg().mustDo("help") || ::arg().mustDo("config")) {
      ::arg().set("daemon")="no";
      ::arg().set("guardian")="no";
    }

    if(::arg().mustDo("guardian") && !isGuarded(argv)) {
      if(::arg().mustDo("daemon")) {
	L.toConsole(Logger::Critical);
	daemonize();
      }
      guardian(argc, argv);  
      // never get here, guardian will reinvoke process
      cerr<<"Um, we did get here!"<<endl;
    }

    if(::arg().mustDo("version")) {
      cerr<<"Version: "VERSION", compiled on "<<__DATE__", "__TIME__;
#ifdef __GNUC__ 
      cerr<<" with gcc version "<<__VERSION__;
#endif
      cout<<endl;
      exit(99);
    }
    
    // we really need to do work - either standalone or as an instance
    
    loadModules();
    BackendMakers().launch(::arg()["launch"]); // vrooooom!

    if(!::arg().getCommands().empty()) {
      cerr<<"Fatal: non-option on the command line, perhaps a '--setting=123' statement missed the '='?"<<endl;
      exit(99);
    }
    
    if(::arg().mustDo("help")) {
      cerr<<"syntax:"<<endl<<endl;
      cerr<<::arg().helpstring(::arg()["help"])<<endl;
      exit(99);
    }
    
    if(::arg().mustDo("config")) {
      cout<<::arg().configstring()<<endl;
      exit(99);
    }

    if(::arg().mustDo("list-modules")) {
      vector<string>modules=BackendMakers().getModules();
      cerr<<"Modules available:"<<endl;
      for(vector<string>::const_iterator i=modules.begin();i!=modules.end();++i)
	cout<<*i<<endl;

      exit(99);
    }

    if(!::arg().asNum("local-port")) {
      L<<Logger::Error<<"Unable to launch, binding to no port or port 0 makes no sense"<<endl;
      exit(99); // this isn't going to fix itself either
    }
    if(!BackendMakers().numLauncheable()) {
      L<<Logger::Error<<"Unable to launch, no backends configured for querying"<<endl;
      exit(99); // this isn't going to fix itself either
    }    
    if(::arg().mustDo("daemon")) {
      L.toConsole(Logger::None);
      if(!isGuarded(argv))
	daemonize();
    }

    if(::arg()["server-id"].empty()) {
      char tmp[128];
      gethostname(tmp, sizeof(tmp)-1);
      ::arg().set("server-id")=tmp;
    }

    if(isGuarded(argv)) {
      L<<Logger::Warning<<"This is a guarded instance of pdns"<<endl;
      dl=new DynListener; // listens on stdin 
    }
    else {
      L<<Logger::Warning<<"This is a standalone pdns"<<endl; 
      
      if(::arg().mustDo("control-console"))
	dl=new DynListener();
      else
	dl=new DynListener(s_programname);
      
      writePid();
    }
    DynListener::registerFunc("SHOW",&DLShowHandler);
    DynListener::registerFunc("RPING",&DLPingHandler);
    DynListener::registerFunc("QUIT",&DLRQuitHandler);
    DynListener::registerFunc("UPTIME",&DLUptimeHandler);
    DynListener::registerFunc("NOTIFY-HOST",&DLNotifyHostHandler);
    DynListener::registerFunc("NOTIFY",&DLNotifyHandler);
    DynListener::registerFunc("RELOAD",&DLReloadHandler);
    DynListener::registerFunc("REDISCOVER",&DLRediscoverHandler);
    DynListener::registerFunc("VERSION",&DLVersionHandler);
    DynListener::registerFunc("PURGE",&DLPurgeHandler);
    DynListener::registerFunc("CCOUNTS",&DLCCHandler);
    DynListener::registerFunc("SET",&DLSettingsHandler);
    DynListener::registerFunc("RETRIEVE",&DLNotifyRetrieveHandler);

    if(!::arg()["tcp-control-address"].empty()) {
      DynListener* dlTCP=new DynListener(ComboAddress(::arg()["tcp-control-address"], ::arg().asNum("tcp-control-port")));
      dlTCP->go();
    }

    // reparse, with error checking
    if(!::arg().mustDo("no-config"))
      ::arg().file(configname.c_str());
    ::arg().parse(argc,argv);
    UeberBackend::go();
    N=new UDPNameserver; // this fails when we are not root, throws exception
    
    if(!::arg().mustDo("disable-tcp"))
      TN=new TCPNameserver; 
  }
  catch(const ArgException &A) {
    L<<Logger::Error<<"Fatal error: "<<A.reason<<endl;
    exit(1);
  }
  
  declareStats();
  DLOG(L<<Logger::Warning<<"Verbose logging in effect"<<endl);
  
  L<<Logger::Warning<<"PowerDNS "<<VERSION<<" (C) 2001-2007 PowerDNS.COM BV ("<<__DATE__", "__TIME__;
#ifdef __GNUC__
  L<<", gcc "__VERSION__;
#endif // add other compilers here
  L<<") starting up"<<endl;

  L<<Logger::Warning<<"PowerDNS comes with ABSOLUTELY NO WARRANTY. "
    "This is free software, and you are welcome to redistribute it "
    "according to the terms of the GPL version 2."<<endl;


  try {

    mainthread();
  }
  catch(AhuException &AE) {
    if(!::arg().mustDo("daemon"))
      cerr<<"Exiting because: "<<AE.reason<<endl;
    L<<Logger::Error<<"Exiting because: "<<AE.reason<<endl;
  }      
  catch(exception &e) {
    if(!::arg().mustDo("daemon"))
      cerr<<"Exiting because of STL error: "<<e.what()<<endl;
    L<<Logger::Error<<"Exiting because of STL error: "<<e.what()<<endl;
  }
  catch(...) {
    cerr<<"Uncaught exception of unknown type - sorry"<<endl;
  }

  exit(1);
  
}


