/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
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
#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#endif
#include "opensslsigners.hh"

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
#include "misc.hh"
#include "dynlistener.hh"
#include "dynhandler.hh"
#include "communicator.hh"
#include "dnsproxy.hh"
#include "utility.hh"
#include "common_startup.hh"
#include "dnsrecords.hh"
#include "version.hh"

#ifdef HAVE_LUA_RECORDS
#include "minicurl.hh"
#endif /* HAVE_LUA_RECORDS */

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
    g_log<<Logger::Critical<<"Unable to open /dev/null: "<<stringerror()<<endl;
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
    g_log<<Logger::Error<<"Guardian is killed, taking down children with us"<<endl;
    kill(cpid,SIGKILL);
    exit(0);
  }
}

static void writePid(void)
{
  if(!::arg().mustDo("write-pid"))
    return;

  string fname=::arg()["socket-dir"];
  if (::arg()["socket-dir"].empty()) {
    if (::arg()["chroot"].empty())
      fname = std::string(LOCALSTATEDIR) + "/pdns";
    else
      fname = ::arg()["chroot"] + "/";
  } else if (!::arg()["socket-dir"].empty() && !::arg()["chroot"].empty()) {
    fname = ::arg()["chroot"] + ::arg()["socket-dir"];
  }

  fname += + "/" + s_programname + ".pid";
  ofstream of(fname.c_str());
  if(of)
    of<<getpid()<<endl;
  else
    g_log<<Logger::Error<<"Writing pid for "<<getpid()<<" to "<<fname<<" failed: "<<stringerror()<<endl;
}

int g_fd1[2], g_fd2[2];
FILE *g_fp;
pthread_mutex_t g_guardian_lock = PTHREAD_MUTEX_INITIALIZER;

// The next two methods are not in dynhandler.cc because they use a few items declared in this file.
static string DLCycleHandler(const vector<string>&parts, pid_t ppid)
{
  kill(cpid, SIGKILL); // why?
  kill(cpid, SIGKILL); // why?
  sleep(1);
  return "ok";
}

static string DLRestHandler(const vector<string>&parts, pid_t ppid)
{
  string line;
  
  for(vector<string>::const_iterator i=parts.begin();i!=parts.end();++i) {
    if(i!=parts.begin())
      line.append(1,' ');
    line.append(*i);
  }
  line.append(1,'\n');
  
  Lock l(&g_guardian_lock);

  try {
    writen2(g_fd1[1],line.c_str(),line.size()+1);
  }
  catch(PDNSException &ae) {
    return "Error communicating with instance: "+ae.reason;
  }
  char mesg[512];
  string response;
  while(fgets(mesg,sizeof(mesg),g_fp)) {
    if(*mesg=='\0')
      break;
    response+=mesg;
  }
  boost::trim_right(response);
  return response;
}



static int guardian(int argc, char **argv)
{
  if(isGuarded(argv))
    return 0;

  int infd=0, outfd=1;

  DynListener dlg(s_programname);
  dlg.registerFunc("QUIT",&DLQuitHandler, "quit daemon");
  dlg.registerFunc("CYCLE",&DLCycleHandler, "restart instance");
  dlg.registerFunc("PING",&DLPingHandler, "ping guardian");
  dlg.registerFunc("STATUS",&DLStatusHandler, "get instance status from guardian");
  dlg.registerRestFunc(&DLRestHandler);
  dlg.go();
  string progname=argv[0];

  bool first=true;
  cpid=0;

  pthread_mutex_lock(&g_guardian_lock);

  for(;;) {
    int pid;
    setStatus("Launching child");
    
    if(pipe(g_fd1)<0 || pipe(g_fd2)<0) {
      g_log<<Logger::Critical<<"Unable to open pipe for coprocess: "<<stringerror()<<endl;
      exit(1);
    }

    if(!(g_fp=fdopen(g_fd2[0],"r"))) {
      g_log<<Logger::Critical<<"Unable to associate a file pointer with pipe: "<<stringerror()<<endl;
      exit(1);
    }
    setbuf(g_fp,0); // no buffering please, confuses select

    if(!(pid=fork())) { // child
      signal(SIGTERM, SIG_DFL);

      signal(SIGHUP, SIG_DFL);
      signal(SIGUSR1, SIG_DFL);
      signal(SIGUSR2, SIG_DFL);

      char **const newargv=new char*[argc+2];
      int n;

      if(::arg()["config-name"]!="") {
        progname+="-"+::arg()["config-name"];
        g_log<<Logger::Error<<"Virtual configuration name: "<<::arg()["config-name"]<<endl;
      }

      newargv[0]=strdup(const_cast<char *>((progname+"-instance").c_str()));
      for(n=1;n<argc;n++) {
        newargv[n]=argv[n];
      }
      newargv[n]=0;
      
      g_log<<Logger::Error<<"Guardian is launching an instance"<<endl;
      close(g_fd1[1]);
      fclose(g_fp); // this closes g_fd2[0] for us

      if(g_fd1[0]!= infd) {
        dup2(g_fd1[0], infd);
        close(g_fd1[0]);
      }

      if(g_fd2[1]!= outfd) {
        dup2(g_fd2[1], outfd);
        close(g_fd2[1]);
      }
      if(execvp(argv[0], newargv)<0) {
        g_log<<Logger::Error<<"Unable to execvp '"<<argv[0]<<"': "<<stringerror()<<endl;
        char **p=newargv;
        while(*p)
          g_log<<Logger::Error<<*p++<<endl;

        exit(1);
      }
      g_log<<Logger::Error<<"execvp returned!!"<<endl;
      // never reached
    }
    else if(pid>0) { // parent
      close(g_fd1[0]);
      close(g_fd2[1]);

      if(first) {
        first=false;
        signal(SIGTERM, takedown);

        signal(SIGHUP, SIG_IGN);
        signal(SIGUSR1, SIG_IGN);
        signal(SIGUSR2, SIG_IGN);

        writePid();
      }
      pthread_mutex_unlock(&g_guardian_lock);  
      int status;
      cpid=pid;
      for(;;) {
        int ret=waitpid(pid,&status,WNOHANG);

        if(ret<0) {
          g_log<<Logger::Error<<"In guardian loop, waitpid returned error: "<<stringerror()<<endl;
          g_log<<Logger::Error<<"Dying"<<endl;
          exit(1);
        }
        else if(ret) // something exited
          break;
        else { // child is alive
          // execute some kind of ping here 
          if(DLQuitPlease())
            takedown(1); // needs a parameter..
          setStatus("Child running on pid "+itoa(pid));
          sleep(1);
        }
      }

      pthread_mutex_lock(&g_guardian_lock);
      close(g_fd1[1]);
      fclose(g_fp);
      g_fp=0;

      if(WIFEXITED(status)) {
        int ret=WEXITSTATUS(status);

        if(ret==99) {
          g_log<<Logger::Error<<"Child requested a stop, exiting"<<endl;
          exit(1);
        }
        setStatus("Child died with code "+itoa(ret));
        g_log<<Logger::Error<<"Our pdns instance exited with code "<<ret<<", respawning"<<endl;

        sleep(1);
        continue;
      }
      if(WIFSIGNALED(status)) {
        int sig=WTERMSIG(status);
        setStatus("Child died because of signal "+itoa(sig));
        g_log<<Logger::Error<<"Our pdns instance ("<<pid<<") exited after signal "<<sig<<endl;
#ifdef WCOREDUMP
        if(WCOREDUMP(status)) 
          g_log<<Logger::Error<<"Dumped core"<<endl;
#endif

        g_log<<Logger::Error<<"Respawning"<<endl;
        sleep(1);
        continue;
      }
      g_log<<Logger::Error<<"No clue what happened! Respawning"<<endl;
    }
    else {
      g_log<<Logger::Error<<"Unable to fork: "<<stringerror()<<endl;
      exit(1);
    }
  }
}

#if defined(__GLIBC__) && !defined(__UCLIBC__)
#include <execinfo.h>
static void tbhandler(int num)
{
  g_log<<Logger::Critical<<"Got a signal "<<num<<", attempting to print trace: "<<endl;
  void *array[20]; //only care about last 17 functions (3 taken with tracing support)
  size_t size;
  char **strings;
  size_t i;
  
  size = backtrace (array, 20);
  strings = backtrace_symbols (array, size); //Need -rdynamic gcc (linker) flag for this to work
  
  for (i = 0; i < size; i++) //skip useless functions
    g_log<<Logger::Error<<strings[i]<<endl;
  
  
  signal(SIGABRT, SIG_DFL);
  abort();//hopefully will give core

}
#endif

//! The main function of pdns, the pdns process
int main(int argc, char **argv)
{
  versionSetProduct(ProductAuthoritative);
  reportAllTypes(); // init MOADNSParser

  s_programname="pdns";
  s_starttime=time(0);

#if defined(__GLIBC__) && !defined(__UCLIBC__)
  signal(SIGSEGV,tbhandler);
  signal(SIGFPE,tbhandler);
  signal(SIGABRT,tbhandler);
  signal(SIGILL,tbhandler);
#endif

  std::ios_base::sync_with_stdio(false);

  g_log.toConsole(Logger::Warning);
  try {
    declareArguments();

    ::arg().laxParse(argc,argv); // do a lax parse
    
    if(::arg().mustDo("version")) {
      showProductVersion();
      showBuildConfiguration();
      exit(99);
    }

    if(::arg()["config-name"]!="") 
      s_programname+="-"+::arg()["config-name"];
    
    g_log.setName(s_programname);
    
    string configname=::arg()["config-dir"]+"/"+s_programname+".conf";
    cleanSlashes(configname);

    if(!::arg().mustDo("config") && !::arg().mustDo("no-config")) // "config" == print a configuration file
      ::arg().laxFile(configname.c_str());
    
    ::arg().laxParse(argc,argv); // reparse so the commandline still wins
    if(!::arg()["logging-facility"].empty()) {
      int val=logFacilityToLOG(::arg().asNum("logging-facility") );
      if(val >= 0)
        g_log.setFacility(val);
      else
        g_log<<Logger::Error<<"Unknown logging facility "<<::arg().asNum("logging-facility") <<endl;
    }

    g_log.setLoglevel((Logger::Urgency)(::arg().asNum("loglevel")));
    g_log.disableSyslog(::arg().mustDo("disable-syslog"));
    g_log.setTimestamps(::arg().mustDo("log-timestamp"));
    g_log.toConsole((Logger::Urgency)(::arg().asNum("loglevel")));  

    if(::arg().mustDo("help") || ::arg().mustDo("config")) {
      ::arg().set("daemon")="no";
      ::arg().set("guardian")="no";
    }

    if(::arg().mustDo("guardian") && !isGuarded(argv)) {
      if(::arg().mustDo("daemon")) {
        g_log.toConsole(Logger::Critical);
        daemonize();
      }
      guardian(argc, argv);  
      // never get here, guardian will reinvoke process
      cerr<<"Um, we did get here!"<<endl;
    }

    
    // we really need to do work - either standalone or as an instance

#if defined(__GLIBC__) && !defined(__UCLIBC__)
    if(!::arg().mustDo("traceback-handler")) {
      g_log<<Logger::Warning<<"Disabling traceback handler"<<endl;
      signal(SIGSEGV,SIG_DFL);
      signal(SIGFPE,SIG_DFL);
      signal(SIGABRT,SIG_DFL);
      signal(SIGILL,SIG_DFL);
    }
#endif

#ifdef HAVE_LIBSODIUM
      if (sodium_init() == -1) {
        cerr<<"Unable to initialize sodium crypto library"<<endl;
        exit(99);
      }
#endif

    openssl_thread_setup();
    openssl_seed();
    /* setup rng */
    dns_random_init();

#ifdef HAVE_LUA_RECORDS
    MiniCurl::init();
#endif /* HAVE_LUA_RECORDS */

    if(!::arg()["load-modules"].empty()) {
      vector<string> modules;

      stringtok(modules,::arg()["load-modules"], ", ");
      if (!UeberBackend::loadModules(modules, ::arg()["module-dir"])) {
        exit(1);
      }
    }

    BackendMakers().launch(::arg()["launch"]); // vrooooom!

    if(!::arg().getCommands().empty()) {
      cerr<<"Fatal: non-option";
      if (::arg().getCommands().size() > 1) {
        cerr<<"s";
      }
      cerr<<" (";
      bool first = true;
      for (auto const c : ::arg().getCommands()) {
        if (!first) {
          cerr<<", ";
        }
        first = false;
        cerr<<c;
      }
      cerr<<") on the command line, perhaps a '--setting=123' statement missed the '='?"<<endl;
      exit(99);
    }
    
    if(::arg().mustDo("help")) {
      cout<<"syntax:"<<endl<<endl;
      cout<<::arg().helpstring(::arg()["help"])<<endl;
      exit(0);
    }
    
    if(::arg().mustDo("config")) {
      cout<<::arg().configstring()<<endl;
      exit(0);
    }

    if(::arg().mustDo("list-modules")) {
      auto modules = BackendMakers().getModules();
      cout<<"Modules available:"<<endl;
      for(const auto& m : modules)
        cout<< m <<endl;

      _exit(99);
    }

    if(!::arg().asNum("local-port")) {
      g_log<<Logger::Error<<"Unable to launch, binding to no port or port 0 makes no sense"<<endl;
      exit(99); // this isn't going to fix itself either
    }
    if(!BackendMakers().numLauncheable()) {
      g_log<<Logger::Error<<"Unable to launch, no backends configured for querying"<<endl;
      exit(99); // this isn't going to fix itself either
    }    
    if(::arg().mustDo("daemon")) {
      g_log.toConsole(Logger::None);
      if(!isGuarded(argv))
        daemonize();
    }

    if(isGuarded(argv)) {
      g_log<<Logger::Warning<<"This is a guarded instance of pdns"<<endl;
      dl=make_unique<DynListener>(); // listens on stdin 
    }
    else {
      g_log<<Logger::Warning<<"This is a standalone pdns"<<endl; 
      
      if(::arg().mustDo("control-console"))
        dl=make_unique<DynListener>();
      else
        dl=std::unique_ptr<DynListener>(new DynListener(s_programname));
      
      writePid();
    }
    DynListener::registerFunc("SHOW",&DLShowHandler, "show a specific statistic or * to get a list", "<statistic>");
    DynListener::registerFunc("RPING",&DLPingHandler, "ping instance");
    DynListener::registerFunc("QUIT",&DLRQuitHandler, "quit daemon");
    DynListener::registerFunc("UPTIME",&DLUptimeHandler, "get instance uptime");
    DynListener::registerFunc("NOTIFY-HOST",&DLNotifyHostHandler, "notify host for specific domain", "<domain> <host>");
    DynListener::registerFunc("NOTIFY",&DLNotifyHandler, "queue a notification", "<domain>");
    DynListener::registerFunc("RELOAD",&DLReloadHandler, "reload all zones");
    DynListener::registerFunc("REDISCOVER",&DLRediscoverHandler, "discover any new zones");
    DynListener::registerFunc("VERSION",&DLVersionHandler, "get instance version");
    DynListener::registerFunc("PURGE",&DLPurgeHandler, "purge entries from packet cache", "[<record>]");
    DynListener::registerFunc("CCOUNTS",&DLCCHandler, "get cache statistics");
    DynListener::registerFunc("QTYPES", &DLQTypesHandler, "get QType statistics");
    DynListener::registerFunc("RESPSIZES", &DLRSizesHandler, "get histogram of response sizes");
    DynListener::registerFunc("REMOTES", &DLRemotesHandler, "get top remotes");
    DynListener::registerFunc("SET",&DLSettingsHandler, "set config variables", "<var> <value>");
    DynListener::registerFunc("RETRIEVE",&DLNotifyRetrieveHandler, "retrieve slave domain", "<domain>");
    DynListener::registerFunc("CURRENT-CONFIG",&DLCurrentConfigHandler, "retrieve the current configuration");
    DynListener::registerFunc("LIST-ZONES",&DLListZones, "show list of zones", "[master|slave|native]");
    DynListener::registerFunc("TOKEN-LOGIN", &DLTokenLogin, "Login to a PKCS#11 token", "<module> <slot> <pin>");

    if(!::arg()["tcp-control-address"].empty()) {
      DynListener* dlTCP=new DynListener(ComboAddress(::arg()["tcp-control-address"], ::arg().asNum("tcp-control-port")));
      dlTCP->go();
    }

    // reparse, with error checking
    if(!::arg().mustDo("no-config"))
      ::arg().file(configname.c_str());
    ::arg().parse(argc,argv);

    if(::arg()["server-id"].empty()) {
      char tmp[128];
      if(gethostname(tmp, sizeof(tmp)-1) == 0) {
        ::arg().set("server-id")=tmp;
      } else {
        g_log<<Logger::Warning<<"Unable to get the hostname, NSID and id.server values will be empty: "<<stringerror()<<endl;
      }
    }

    UeberBackend::go();
    N=std::make_shared<UDPNameserver>(); // this fails when we are not root, throws exception
    g_udpReceivers.push_back(N);

    size_t rthreads = ::arg().asNum("receiver-threads", 1);
    if (rthreads > 1 && N->canReusePort()) {
      g_udpReceivers.resize(rthreads);

      for (size_t idx = 1; idx < rthreads; idx++) {
        try {
          g_udpReceivers[idx] = std::make_shared<UDPNameserver>(true);
        }
        catch(const PDNSException& e) {
          g_log<<Logger::Error<<"Unable to reuse port, falling back to original bind"<<endl;
          break;
        }
      }
    }

    TN = make_unique<TCPNameserver>();
  }
  catch(const ArgException &A) {
    g_log<<Logger::Error<<"Fatal error: "<<A.reason<<endl;
    exit(1);
  }
  
  declareStats();
  S.blacklist("special-memory-usage");

  DLOG(g_log<<Logger::Warning<<"Verbose logging in effect"<<endl);

  showProductVersion();

  try {
    mainthread();
  }
  catch(PDNSException &AE) {
    if(!::arg().mustDo("daemon"))
      cerr<<"Exiting because: "<<AE.reason<<endl;
    g_log<<Logger::Error<<"Exiting because: "<<AE.reason<<endl;
  }      
  catch(std::exception &e) {
    if(!::arg().mustDo("daemon"))
      cerr<<"Exiting because of STL error: "<<e.what()<<endl;
    g_log<<Logger::Error<<"Exiting because of STL error: "<<e.what()<<endl;
  }
  catch(...) {
    cerr<<"Uncaught exception of unknown type - sorry"<<endl;
  }

  exit(1);
  
}


