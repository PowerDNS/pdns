 /*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2013  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include <cstring>
#include <string>
#include <map>
#include <sys/types.h>
#include <sys/un.h>
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>
#include <boost/algorithm/string.hpp>
#include <boost/shared_ptr.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <iostream>
#include <sstream>
#include <sys/types.h>
#include <signal.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <boost/algorithm/string.hpp> 
#include "misc.hh"
#include "dns.hh"
#include "arguments.hh"
#include "dnsbackend.hh"
#include "dynlistener.hh"
#include "dnspacket.hh"
#include "logger.hh"
#include "statbag.hh"

extern StatBag S;

DynListener::g_funkdb_t DynListener::s_funcdb;
DynListener::g_funk_t* DynListener::s_restfunc;

DynListener::~DynListener()
{
  if(!d_socketname.empty())
    unlink(d_socketname.c_str());
}

void DynListener::createSocketAndBind(int family, struct sockaddr*local, size_t len)
{
  d_s=socket(family, SOCK_STREAM,0);
  Utility::setCloseOnExec(d_s);

  if(d_s < 0) {
    if (family == AF_UNIX)
      L<<Logger::Error<<"Unable to create control socket at '"<<((struct sockaddr_un*)local)->sun_path<<"', reason: "<<strerror(errno)<<endl;
    else
      L<<Logger::Error<<"Unable to create control socket on '"<<((ComboAddress *)local)->toStringWithPort()<<"', reason: "<<strerror(errno)<<endl;
    exit(1);
  }
  
  int tmp=1;
  if(setsockopt(d_s,SOL_SOCKET,SO_REUSEADDR,(char*)&tmp,sizeof tmp)<0)
    throw PDNSException(string("Setsockopt failed on control socket: ")+strerror(errno));
    
  if(bind(d_s, local, len) < 0) {
    if (family == AF_UNIX)
      L<<Logger::Critical<<"Unable to bind to control socket at '"<<((struct sockaddr_un*)local)->sun_path<<"', reason: "<<strerror(errno)<<endl;
    else
      L<<Logger::Critical<<"Unable to bind to control socket on '"<<((ComboAddress *)local)->toStringWithPort()<<"', reason: "<<strerror(errno)<<endl;
    exit(1);
  }
}

/* this does a simplistic check, if we can connect, we consider it live. If we can't connect because
   of access denied, we must consider it dead, nothing we can do about it.
*/
bool DynListener::testLive(const string& fname)
{
  struct sockaddr_un addr;
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if(fd < 0) { // we'll have bigger issues down the road
    return false;
  }

  if (makeUNsockaddr(fname, &addr)) {
    L<<Logger::Critical<<"Unable to open controlsocket, path '"<<fname<<"' is not a valid UNIX socket path."<<endl;
    exit(1);
  }

  int status = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
  close(fd);
  return status==0;
}

void DynListener::listenOnUnixDomain(const string& fname)
{
  if(testLive(fname)) {
    L<<Logger::Critical<<"Previous controlsocket '"<<fname<<"' is in use"<<endl;
    exit(1);
  }
  int err=unlink(fname.c_str());
  if(err < 0 && errno!=ENOENT) {
    L<<Logger::Critical<<"Unable to remove (previous) controlsocket at '"<<fname<<"': "<<strerror(errno)<<endl;
    exit(1);
  }

  struct sockaddr_un local;
  if (makeUNsockaddr(fname, &local)) {
    L<<Logger::Critical<<"Unable to bind to controlsocket, path '"<<fname<<"' is not a valid UNIX socket path."<<endl;
    exit(1);
  }
  
  createSocketAndBind(AF_UNIX, (struct sockaddr*)& local, sizeof(local));
  d_socketname=fname;
  if(!arg()["setgid"].empty()) {
    if(chmod(fname.c_str(),0660)<0)
      L<<Logger::Error<<"Unable to change group access mode of controlsocket at '"<<fname<<"', reason: "<<strerror(errno)<<endl;
    if(chown(fname.c_str(),static_cast<uid_t>(-1),Utility::makeGidNumeric(arg()["setgid"]))<0)
      L<<Logger::Error<<"Unable to change group ownership of controlsocket at '"<<fname<<"', reason: "<<strerror(errno)<<endl;
  }
  
  listen(d_s, 10);
  
  L<<Logger::Warning<<"Listening on controlsocket in '"<<fname<<"'"<<endl;
  d_nonlocal=true;
}

void DynListener::listenOnTCP(const ComboAddress& local)
{
  createSocketAndBind(AF_INET, (struct sockaddr*)& local, local.getSocklen());
  listen(d_s, 10);

  d_socketaddress=local;
  L<<Logger::Warning<<"Listening on controlsocket on '"<<local.toStringWithPort()<<"'"<<endl;
  d_nonlocal=true;

  if(!::arg()["tcp-control-range"].empty()) {
    d_tcprange.toMasks(::arg()["tcp-control-range"]);
    L<<Logger::Warning<<"Only allowing TCP control from: "<<d_tcprange.toString()<<endl;
  }
}


DynListener::DynListener(const ComboAddress& local)
{
  listenOnTCP(local);
  d_tcp=true;
}

DynListener::DynListener(const string &progname)
{
  if(!progname.empty()) {
    string socketname=arg()["socket-dir"]+"/";
    cleanSlashes(socketname);
    
    if(!mkdir(socketname.c_str(),0700)) // make /var directory, if needed
      L<<Logger::Warning<<"Created local state directory '"<<socketname<<"'"<<endl;
    else if(errno!=EEXIST) {
      L<<Logger::Critical<<"FATAL: Unable to create socket directory ("<<socketname<<") and it does not exist yet"<<endl;
      exit(1);
    }
    
    socketname+=progname+".controlsocket";
    listenOnUnixDomain(socketname);
  }
  else
    d_nonlocal=false; // we listen on stdin!
  d_tcp=false;
}

void DynListener::go()
{
  d_ppid=getpid();
  pthread_create(&d_tid,0,&DynListener::theListenerHelper,this);
}

void *DynListener::theListenerHelper(void *p)
{
  DynListener *us=static_cast<DynListener *>(p);
  us->theListener();
  L<<Logger::Error<<"Control listener aborted, please file a bug!"<<endl;
  return 0;
}

string DynListener::getLine()
{
  vector<char> mesg;
  mesg.resize(1024000);

  int len;

  ComboAddress remote;
  socklen_t remlen=remote.getSocklen();

  if(d_nonlocal) {
    for(;;) {
      d_client=accept(d_s,(sockaddr*)&remote,&remlen);
      if(d_client<0) {
        if(errno!=EINTR)
          L<<Logger::Error<<"Unable to accept controlsocket connection ("<<d_s<<"): "<<strerror(errno)<<endl;
        continue;
      }

      if(d_tcp && !d_tcprange.match(&remote)) { // checks if the remote is within the permitted range.
        L<<Logger::Error<<"Access denied to remote "<<remote.toString()<<" because not allowed"<<endl;
        writen2(d_client, "Access denied to "+remote.toString()+"\n");
        close(d_client);
        continue;
      }

      boost::shared_ptr<FILE> fp=boost::shared_ptr<FILE>(fdopen(dup(d_client), "r"), fclose);
      if(d_tcp) {
        if(!fgets(&mesg[0], mesg.size(), fp.get())) {
          L<<Logger::Error<<"Unable to receive password from controlsocket ("<<d_client<<"): "<<strerror(errno)<<endl;
          close(d_client);
          continue;
        }
        string password(&mesg[0]);
        boost::trim(password);
        if(password.empty() || password!=arg()["tcp-control-secret"]) {
          L<<Logger::Error<<"Wrong password on TCP control socket"<<endl;
          writen2(d_client, "Wrong password");

          close(d_client);
          continue;
        }
      }
      errno=0;
      if(!fgets(&mesg[0], mesg.size(), fp.get())) {
        if(errno)
          L<<Logger::Error<<"Unable to receive line from controlsocket ("<<d_client<<"): "<<strerror(errno)<<endl;
        close(d_client);
        continue;
      }
      
      if(strlen(&mesg[0]) == mesg.size()) {
        L<<Logger::Error<<"Line on controlsocket ("<<d_client<<") was too long"<<endl;
        close(d_client);
        continue;
      }
      break;
    }
  }
  else {
    if(isatty(0))
      if(write(1, "% ", 2) !=2)
        throw PDNSException("Writing to console: "+stringerror());
    if((len=read(0, &mesg[0], mesg.size())) < 0) 
      throw PDNSException("Reading from the control pipe: "+stringerror());
    else if(len==0)
      throw PDNSException("Guardian exited - going down as well");

    if(len == (int)mesg.size())
      throw PDNSException("Line on control console was too long");

    mesg[len]=0;
  }
  
  return &mesg[0];
}

void DynListener::sendlines(const string &l)
{
  if(d_nonlocal) {
    unsigned int sent=0;
    int ret;
    while(sent < l.length()) {
      ret=send(d_client, l.c_str()+sent, l.length()-sent, 0); 

      if(ret<0 || !ret) {
        L<<Logger::Error<<"Error sending data to pdns_control: "<<stringerror()<<endl;
        break;
      }
      sent+=ret;
    }
    close(d_client);
  } else {
    string lines=l;
    if(!lines.empty() && lines[lines.length()-1] != '\n')
      lines.append("\n");
    lines.append(1, '\0');
    lines.append(1, '\n');
    if((unsigned int)write(1, lines.c_str(), lines.length()) != lines.length())
      L<<Logger::Error<<"Error sending data to console: "<<stringerror()<<endl;
  }
}

void DynListener::registerFunc(const string &name, g_funk_t *gf, const string &usage, const string &args)
{
  g_funkwithusage_t e = {gf, args, usage};
  s_funcdb[name]=e;
}

void DynListener::registerRestFunc(g_funk_t *gf)
{
  s_restfunc=gf;
}

void DynListener::theListener()
{
  try {
    signal(SIGPIPE,SIG_IGN);

    for(int n=0;;++n) {
      string line=getLine();
      boost::trim_right(line);

      vector<string>parts;
      stringtok(parts,line," ");
      if(parts.empty()) {
        sendlines("Empty line");
        continue;
      }

      try {
        parts[0] = toUpper( parts[0] );
        if(s_funcdb.count(parts[0]))
          sendlines((*(s_funcdb[parts[0]].func))(parts,d_ppid));
        else if (parts[0] == "HELP")
          sendlines(getHelp());
        else if(s_restfunc)
          sendlines((*s_restfunc)(parts,d_ppid));
        else
          sendlines("Unknown command: '"+parts[0]+"'");
      }
      catch(PDNSException &AE) {
        L<<Logger::Error<<"Non-fatal error in control listener command '"<<line<<"': "<<AE.reason<<endl;
      }
      catch(string &E) {
        L<<Logger::Error<<"Non-fatal error 2 in control listener command '"<<line<<"': "<<E<<endl;
      }
      catch(std::exception& e) {
        L<<Logger::Error<<"Non-fatal STL error in control listener command '"<<line<<"': "<<e.what()<<endl;
      }
      catch(...) {
        L<<Logger::Error<<"Non-fatal error in control listener command '"<<line<<"': unknown exception occurred"<<endl;
      }
    }
  }
  catch(PDNSException &AE) {
    L<<Logger::Error<<"Fatal error in control listener: "<<AE.reason<<endl;
  }
  catch(string &E) {
    L<<Logger::Error<<"Fatal error 2 in control listener: "<<E<<endl;
  }
  catch(std::exception& e) {
    L<<Logger::Error<<"Fatal STL error in control listener: "<<e.what()<<endl;
  }
  catch(...) {
    L<<Logger::Error<<"Fatal: unknown exception in control listener occurred"<<endl;
  }
}


string DynListener::getHelp()
{
  vector<string> funcs;
  string rest;

  // s_restfunc, when in guardian mode, is the function that
  // can pass commands on to the guarded instance
  // we just pass it HELP and merge it with our own list
  if(s_restfunc)
  {
    vector<string> parts;
    parts.push_back("HELP");
    rest=((*s_restfunc)(parts,d_ppid));
    boost::split(funcs, rest, boost::is_any_of("\n"));
  }

  const boost::format fmter("%|-32| %||");

  for(g_funkdb_t::const_iterator i=s_funcdb.begin();i!=s_funcdb.end();++i) {
    funcs.push_back(str(boost::format(fmter) % (toLower(i->first)+" "+i->second.args) % i->second.usage));
  }
  sort(funcs.begin(), funcs.end());

  // hack: this removes the duplicate quit method
  funcs.resize(unique(funcs.begin(), funcs.end()) - funcs.begin());
  return boost::join(funcs, "\n");
}
